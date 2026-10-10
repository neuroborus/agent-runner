import { performance } from "node:perf_hooks";
import {
  dense,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import { assessWindowsDomain, assertWindowsRetirement } from "./recovery.js";

export const WINDOWS_OWNERSHIP_CASES = Object.freeze([
  "detached",
  "reparent",
  "nested-job",
  "breakaway",
  "spoofed-parent",
  "wmi",
  "com",
  "service",
  "process-limit",
  "cancel",
  "owner-loss",
  "helper-loss",
  "last-handle-close",
  "admission-interruption",
  "receipt-before",
  "receipt-after",
  "stale-identity",
]);
const DENIALS = new Set([
  "breakaway",
  "spoofed-parent",
  "wmi",
  "com",
  "service",
]);
const EARLY = new Set([
  "admission-interruption",
  "receipt-before",
  "receipt-after",
]);

/** Finite native cases corroborate the separately inspected inheritance and
 * token/object-access argument. They never establish containment on their own. */
export async function runWindowsOwnershipCase(
  caseId,
  input,
  effects,
  {
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const request = normalizeWindowsLaunch(input);
  requireWindows(
    WINDOWS_OWNERSHIP_CASES.includes(caseId) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    caseId,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    status: "BLOCKED",
    phase: "composition",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const key of [
    "verifyComposition",
    "admit",
    "observe",
    "armFault",
    "fireFault",
    "recoverAndRetire",
    "verify",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("windows-ownership-" + key);
  let persistence = Promise.resolve();
  const save = () => {
    const snapshot = structuredClone(record),
      write = () => effects.persist(snapshot);
    persistence = persistence.then(write, write);
    return persistence;
  };
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const start = now();
  let rejectDeadline,
    expired = false;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  deadline.catch(() => {});
  const timer = schedule(() => {
    expired = true;
    rejectDeadline(new Error("Windows ownership deadline"));
  }, 60000);
  const wait = async (value) => {
    const result = await Promise.race([value, deadline]);
    requireWindows(
      !expired &&
        Number.isFinite(now() - start) &&
        now() - start >= 0 &&
        now() - start <= 60000,
    );
    return result;
  };
  let admitted,
    retirementAttempted = false,
    retired;
  try {
    const composition = await wait(
      effects.verifyComposition(caseId, structuredClone(request)),
    );
    const compositionVerifier = systemIdentity(composition.verifier);
    requireWindows(
      composition.independent === true &&
        composition.sourceSha256 === request.bindings.source &&
        composition.policySha256 === request.bindings.policy &&
        hash(composition.nativeEventSha256) &&
        composition.sdkExportsVerified === true &&
        composition.immutableRestrictedToken === true &&
        composition.creationTimeJob === true &&
        composition.noBreakaway === true &&
        composition.nestedJobsContained === true &&
        composition.parentObjectAccessDenied === true &&
        composition.hostServicesDenied === true &&
        composition.noDelegation === true &&
        composition.jobDaclProtected === true &&
        composition.receiptDaclProtected === true &&
        composition.noForeignHandles === true &&
        composition.processLimit === 32,
    );
    record.compositionSha256 = composition.nativeEventSha256;
    record.status = "RUNNING";
    record.phase = "admission";
    await wait(save());
    admitted = structuredClone(
      await wait(effects.admit(caseId, structuredClone(request))),
    );
    requireWindows(
      (EARLY.has(caseId)
        ? ["RUNNING", "FAIL"].includes(admitted.status)
        : admitted.status === "ADMITTED") &&
        admitted.admission === "possible" &&
        admitted.candidateSha === request.candidateSha &&
        admitted.nonce === request.nonce &&
        hash(admitted.requestSha256) &&
        admitted.reservation === "RETAINED" &&
        admitted.setup?.account.sid === admitted.accountSid &&
        hash(admitted.setup.job.heldObjectSha256),
    );
    record.requestSha256 = admitted.requestSha256;
    record.accountSid = admitted.accountSid;
    record.jobObjectSha256 = admitted.setup.job.heldObjectSha256;
    record.phase = "observation";
    await wait(save());
    const observed = await wait(
      effects.observe(
        caseId,
        structuredClone(request),
        structuredClone(admitted),
      ),
    );
    const observer = systemIdentity(observed.verifier);
    requireWindows(
      observer.pid !== compositionVerifier.pid &&
        observed.independent === true &&
        observed.caseId === caseId &&
        observed.nonce === request.nonce &&
        observed.requestSha256 === record.requestSha256 &&
        observed.attempted === true &&
        observed.complete === true &&
        observed.timedOut === false &&
        observed.outsideUnchanged === true &&
        hash(observed.nativeEventSha256) &&
        hash(observed.bytesSha256),
    );
    const members = dense(observed.members, 32).map(normalizeWindowsIdentity);
    requireWindows(
      new Set(members.map((member) => member.pid)).size === members.length &&
        members.every(
          (member) =>
            member.userSid === admitted.accountSid && member.sessionId === 0,
        ),
    );
    if (!EARLY.has(caseId))
      requireWindows(
        members.length > 0 &&
          members.some((member) =>
            sameWindowsIdentity(member, admitted.payload),
          ),
      );
    if (["detached", "reparent"].includes(caseId))
      requireWindows(
        members.length >= 2 &&
          observed.childAcknowledged === true &&
          observed.creationTimeJobVerified === true &&
          observed.inheritedTokenVerified === true &&
          (caseId !== "reparent" || observed.creatorSignaled === true),
      );
    if (caseId === "nested-job")
      requireWindows(
        observed.outerMembershipVerified === true &&
          ["contained", "ERROR_ACCESS_DENIED"].includes(observed.nestedOutcome),
      );
    if (DENIALS.has(caseId))
      requireWindows(
        observed.control?.ready === true &&
          observed.control.reachable === true &&
          observed.control.operation === caseId &&
          hash(observed.control.nativeEventSha256) &&
          hash(observed.control.protectedBeforeSha256) &&
          observed.control.protectedAfterSha256 ===
            observed.control.protectedBeforeSha256 &&
          observed.denied === true &&
          [
            "ERROR_ACCESS_DENIED",
            "E_ACCESSDENIED",
            "WBEM_E_ACCESS_DENIED",
          ].includes(observed.nativeError),
      );
    if (caseId === "process-limit")
      requireWindows(
        members.length === 32 &&
          observed.activeProcessLimit === 32 &&
          observed.creationRejected === true &&
          ["ERROR_ACCESS_DENIED", "ERROR_NOT_ENOUGH_QUOTA"].includes(
            observed.nativeError,
          ),
      );
    if (caseId === "stale-identity") {
      const stale = normalizeWindowsIdentity(observed.stale);
      requireWindows(
        observed.staleRejected === true &&
          observed.forcedPidReuse === false &&
          stale.pid === admitted.payload.pid &&
          stale.creationTime !== admitted.payload.creationTime &&
          stale.userSid === admitted.payload.userSid &&
          stale.sessionId === admitted.payload.sessionId &&
          sameWindowsIdentity(observed.current, admitted.payload),
      );
    }
    if (EARLY.has(caseId))
      requireWindows(
        members.length <= 1 &&
          observed.payloadReleased === false &&
          observed.receiptBoundary ===
            (caseId === "receipt-after" ? "after" : "before") &&
          observed.barrierAcknowledged === true,
      );
    record.members = members;
    record.nativeEventSha256 = observed.nativeEventSha256;
    record.bytesSha256 = observed.bytesSha256;
    record.phase = "fault-barrier";
    await wait(save());
    const armed = await wait(
      effects.armFault(
        caseId,
        structuredClone(request),
        structuredClone(record),
      ),
    );
    requireWindows(
      armed.armed === true &&
        armed.independent === true &&
        armed.caseId === caseId &&
        armed.point === caseId &&
        armed.nonce === request.nonce &&
        armed.requestSha256 === record.requestSha256 &&
        hash(armed.receiptSha256),
    );
    if (caseId === "last-handle-close")
      requireWindows(
        armed.jobHandleHeld === false &&
          armed.processHandlesVerified === true &&
          dense(armed.processHandles, 32).length === members.length &&
          members.every(
            (member) =>
              armed.processHandles.filter((identity) =>
                sameWindowsIdentity(identity, member),
              ).length === 1,
          ) &&
          armed.holderInventoryComplete === true,
      );
    record.faultSha256 = armed.receiptSha256;
    record.phase = "fault-possible";
    await wait(save());
    const fired = await wait(
      effects.fireFault(
        caseId,
        structuredClone(request),
        structuredClone(armed),
      ),
    );
    requireWindows(
      fired.acknowledged === true &&
        fired.caseId === caseId &&
        fired.nonce === request.nonce &&
        fired.faultSha256 === record.faultSha256 &&
        hash(fired.nativeEventSha256),
    );
    record.phase = "recovery";
    await wait(save());
    retirementAttempted = true;
    retired = await wait(
      effects.recoverAndRetire(structuredClone(request), record.requestSha256),
    );
    const retirementVerifier = assertWindowsRetirement(
      retired,
      request,
      record.requestSha256,
      record.accountSid,
      record.jobObjectSha256,
    );
    requireWindows(
      members.every((member) =>
        retired.members.some((identity) =>
          sameWindowsIdentity(member, identity),
        ),
      ),
    );
    const fresh = await wait(
      effects.verify(
        caseId,
        structuredClone(request),
        structuredClone(retired),
        structuredClone(record),
      ),
    );
    const verifier = systemIdentity(fresh.verifier);
    requireWindows(
      fresh.independent === true &&
        fresh.requestSha256 === record.requestSha256 &&
        fresh.nonce === request.nonce &&
        fresh.helpersSettled === true &&
        fresh.knownProcessHandlesSignaled === true &&
        fresh.jobHolders === 0 &&
        fresh.outsideUnchanged === true &&
        fresh.reservation === "RETAINED" &&
        hash(fresh.nativeEventSha256) &&
        verifier.pid !== compositionVerifier.pid &&
        verifier.pid !== observer.pid &&
        verifier.pid !== retirementVerifier.pid &&
        !retired.helpers.some((entry) => entry.identity.pid === verifier.pid) &&
        assessWindowsDomain(
          fresh.enumeration,
          record.accountSid,
          record.jobObjectSha256,
          false,
        ).every((entry) => entry.signaled),
    );
    if (caseId === "last-handle-close")
      requireWindows(
        fresh.lastHandleCloseObserved === true &&
          fresh.jobAbsent === true &&
          fresh.jobHandleHeld === false,
      );
    record.status = "OBSERVED";
    record.phase = "verified";
    record.verifier = verifier;
    await wait(save());
    return structuredClone(record);
  } catch {
    record.status = "FAIL";
    record.cleanup = { status: "RETAINED" };
    await save();
    // Preserve the failed case. Cleanup is separately bounded by the retirement
    // owner and cannot convert missing/failed observation into a passing proof.
    if (!retirementAttempted && record.requestSha256) {
      retirementAttempted = true;
      let cleanupTimer;
      const cleanupDeadline = new Promise((_, reject) => {
        cleanupTimer = schedule(
          () => reject(new Error("Windows failure retirement deadline")),
          30000,
        );
      });
      cleanupDeadline.catch(() => {});
      try {
        retired = await Promise.race([
          effects.recoverAndRetire(
            structuredClone(request),
            record.requestSha256,
          ),
          cleanupDeadline,
        ]);
      } catch {
        /* Protected recovery intent retains unknown possible effects. */
      } finally {
        cancel(cleanupTimer);
      }
    }
    try {
      assertWindowsRetirement(
        retired,
        request,
        record.requestSha256,
        record.accountSid,
        record.jobObjectSha256,
      );
      record.cleanup = { status: "RETIRED", helpersSettled: true };
    } catch {
      /* Uncertain retirement retains all reservations. */
    }
    await save();
    return structuredClone(record);
  } finally {
    cancel(timer);
  }
}
