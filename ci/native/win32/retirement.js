import { performance } from "node:perf_hooks";
import { isWindows2025Image } from "../index.js";
import {
  dense,
  hash,
  digest,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsIdentity,
  systemIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import {
  assessWindowsRecovery,
  assessWindowsDomain,
  windowsCustodyObject,
} from "./recovery.js";

/** External privileged native owners only. Termination authority is a verified
 * held Job, never a PID/name/account-wide kill. Every reservation is retained. */
export async function retireWindowsDomain(
  input,
  approvedSha256,
  effects,
  {
    platform = process.platform,
    architecture = process.arch,
    env = process.env,
    build = "",
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const request = normalizeWindowsLaunch(input);
  requireWindows(
    platform === "win32" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      isWindows2025Image({
        build,
        imageOS: env.ImageOS,
        imageVersion: env.ImageVersion,
      }) &&
      typeof effects?.persist === "function" &&
      hash(approvedSha256),
  );
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    requestSha256: approvedSha256,
    status: "BLOCKED",
    phase: "recovery",
    reservation: "RETAINED",
    missingInputs: [],
    helpers: [],
    members: [],
    work: 0,
    noLiveMembers: false,
    helpersSettled: false,
    independent: false,
    freshVerifier: null,
  };
  for (const key of [
    "recover",
    "verifyRecovery",
    "verifyReceipt",
    "stopAdmissions",
    "snapshot",
    "terminateJob",
    "waitProcesses",
    "verifyRetirement",
    "settleCustody",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("windows-retirement-" + key);
  let persistence = Promise.resolve(),
    expired = false,
    failed = false,
    close;
  const save = () => {
    const snapshot = structuredClone(record);
    const write = () => effects.persist(snapshot);
    persistence = persistence.then(write, write);
    return persistence;
  };
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const started = now();
  let rejectDeadline;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  deadline.catch(() => {});
  const abort = () => {
    try {
      close?.();
    } catch {
      /* Failed transport closure leaves native custody uncertain and reserved. */
    }
  };
  const timer = schedule(() => {
    expired = true;
    abort();
    rejectDeadline(new Error("Windows retirement deadline"));
  }, 30000);
  const bounded = () =>
    requireWindows(
      !failed &&
        !expired &&
        Number.isFinite(now() - started) &&
        now() - started >= 0 &&
        now() - started <= 30000 &&
        record.work <= 1024,
    );
  const wait = async (value) => {
    const result = await Promise.race([value, deadline]);
    bounded();
    return result;
  };
  const bindings = (value) =>
    requireWindows(
      value &&
        Object.keys(value).length === Object.keys(request.bindings).length &&
        Object.keys(request.bindings).every(
          (key) => value[key] === request.bindings[key],
        ),
    );
  const verifiers = [];
  const verifier = (value, fresh = false) => {
    const identity = systemIdentity(value);
    requireWindows(
      !record.helpers.some((entry) => entry.identity.pid === identity.pid) &&
        !record.members.some((member) => member.pid === identity.pid) &&
        (!fresh || !verifiers.some((entry) => entry.pid === identity.pid)),
    );
    verifiers.push(identity);
    return identity;
  };
  const receipt = async () => {
    await wait(save());
    const result = await wait(
      effects.verifyReceipt(structuredClone(request), structuredClone(record)),
    );
    verifier(result.verifier);
    requireWindows(
      result.independent === true &&
        result.immutable === true &&
        result.sha256 === digest(JSON.stringify(record) + "\n") &&
        hash(result.receiptSha256),
    );
  };
  try {
    const recovered = await wait(
      effects.recover(structuredClone(request), approvedSha256),
    );
    const domain = assessWindowsRecovery(recovered, request, approvedSha256);
    if (domain.missingInputs) {
      record.missingInputs = domain.missingInputs;
      await wait(save());
      return record;
    }
    Object.assign(record, {
      accountSid: domain.accountSid,
      jobObjectSha256: domain.job.heldObjectSha256,
      jobName: domain.job.name,
      receiptSha256: domain.receiptSha256,
      custodyIdentity: domain.custodyIdentity,
      helpers: domain.helpers,
      members: domain.members,
      status: "RUNNING",
      phase: "custody",
      custodyAdmission: "possible",
    });
    await wait(save());
    const verified = await wait(
      effects.verifyRecovery(structuredClone(request), structuredClone(record)),
    );
    bindings(verified.bindings);
    verifier(verified.verifier);
    requireWindows(
      verified.independent === true &&
        verified.requestSha256 === approvedSha256 &&
        verified.privilegedContext === "local-system-session-0" &&
        verified.sdkExportsVerified === true &&
        verified.possibleEffectsInventoried === true &&
        verified.helperInventoryComplete === true &&
        verified.receiptSha256 === domain.receiptSha256 &&
        hash(verified.nativeEventSha256) &&
        windowsCustodyObject(verified.custody, request.custody) ===
          domain.custodyIdentity &&
        verified.accountSid === record.accountSid &&
        verified.accountReserved === true &&
        verified.namesNeverReused === true &&
        verified.policyStillInstalled === true &&
        verified.compositionSha256 === request.bindings.policy &&
        verified.immutableTokenInheritance === true &&
        verified.noHostMediatedCreation === true &&
        verified.noBreakaway === true &&
        verified.nestedJobsContained === true &&
        verified.parentSpoofDenied === true &&
        verified.jobObjectSha256 === record.jobObjectSha256 &&
        verified.processLimit === 32 &&
        typeof verified.jobPresent === "boolean" &&
        verified.exactJobVerified === true &&
        (verified.jobPresent
          ? verified.heldJobVerified === true
          : verified.jobHandleHeld === false &&
            verified.jobAbsenceVerified === true) &&
        typeof verified.close === "function",
    );
    close = verified.close;
    const custodian = {
      role: "recovery",
      identity: systemIdentity(verified.custodian.identity),
      imageSha256: verified.custodian.imageSha256,
      sourceSha256: verified.custodian.sourceSha256,
      settled: false,
    };
    requireWindows(
      record.helpers.length < 32 &&
        hash(custodian.imageSha256) &&
        hash(custodian.sourceSha256) &&
        verified.recoveryImageSha256 === custodian.imageSha256 &&
        verified.recoverySourceSha256 === custodian.sourceSha256 &&
        !record.helpers.some(
          (entry) => entry.identity.pid === custodian.identity.pid,
        ) &&
        !verifiers.some((entry) => entry.pid === custodian.identity.pid),
    );
    record.helpers.push(custodian);
    record.jobPresent = verified.jobPresent;
    const held = dense(verified.processHandles, 256).map(
      normalizeWindowsIdentity,
    );
    requireWindows(
      verified.processHandlesVerified === true &&
        held.every(
          (identity) =>
            identity.userSid === record.accountSid && identity.sessionId === 0,
        ) &&
        new Set(held.map((identity) => identity.pid)).size === held.length &&
        record.members.every((member) =>
          held.some((identity) => sameWindowsIdentity(identity, member)),
        ),
    );
    for (const identity of held)
      if (
        !record.members.some((member) => sameWindowsIdentity(member, identity))
      )
        record.members.push(identity);
    requireWindows(record.members.length <= 256);
    record.phase = "stop-admissions";
    await receipt();
    const stopped = await wait(
      effects.stopAdmissions(structuredClone(request), structuredClone(record)),
    );
    verifier(stopped.verifier);
    requireWindows(
      stopped.independent === true &&
        stopped.closed === true &&
        stopped.requestSha256 === approvedSha256 &&
        stopped.creationSealed === true &&
        hash(stopped.receiptSha256) &&
        dense(stopped.helpersSettled, 32).length ===
          record.helpers.length - 1 &&
        record.helpers
          .slice(0, -1)
          .every(
            (entry) =>
              stopped.helpersSettled.filter((identity) =>
                sameWindowsIdentity(identity, entry.identity),
              ).length === 1,
          ),
    );
    record.stopSha256 = stopped.receiptSha256;
    for (let pass = 0; pass < 8; pass++) {
      record.phase = "enumerate";
      record.work++;
      bounded();
      await receipt();
      const observed = await wait(
        effects.snapshot(structuredClone(request), structuredClone(record)),
      );
      verifier(observed.verifier);
      const entries = assessWindowsDomain(
        observed.enumeration,
        record.accountSid,
        record.jobObjectSha256,
        record.jobPresent,
      );
      for (const { identity } of entries)
        if (
          !record.members.some((member) =>
            sameWindowsIdentity(member, identity),
          )
        )
          record.members.push(identity);
      requireWindows(record.members.length <= 256);
      record.work += entries.length;
      bounded();
      // A disappeared Job authorizes only waits and an independent principal
      // census. Live account processes cannot be killed through a guessed name.
      requireWindows(
        record.jobPresent || entries.every((entry) => entry.signaled),
      );
      if (record.jobPresent && entries.some((entry) => !entry.signaled)) {
        record.phase = "terminate-job";
        await receipt();
        const terminated = await wait(
          effects.terminateJob(
            structuredClone(request),
            structuredClone(record),
          ),
        );
        verifier(terminated.verifier);
        requireWindows(
          terminated.independent === true &&
            terminated.heldJobVerified === true &&
            terminated.jobObjectSha256 === record.jobObjectSha256 &&
            terminated.requestSha256 === approvedSha256 &&
            terminated.terminated === true &&
            hash(terminated.nativeEventSha256),
        );
      }
      record.phase = "wait-processes";
      await receipt();
      const waited = await wait(
        effects.waitProcesses(
          structuredClone(request),
          structuredClone(record),
        ),
      );
      verifier(waited.verifier);
      const signaled = dense(waited.signaled, 256).map(
        normalizeWindowsIdentity,
      );
      requireWindows(
        waited.independent === true &&
          waited.requestSha256 === approvedSha256 &&
          waited.heldHandlesVerified === true &&
          signaled.length === record.members.length &&
          record.members.every(
            (member) =>
              signaled.filter((identity) =>
                sameWindowsIdentity(identity, member),
              ).length === 1,
          ),
      );
      record.phase = "fresh-verification";
      await receipt();
      const fresh = await wait(
        effects.verifyRetirement(
          structuredClone(request),
          structuredClone(record),
        ),
      );
      const freshIdentity = verifier(fresh.verifier, true);
      bindings(fresh.bindings);
      requireWindows(
        fresh.independent === true &&
          fresh.requestSha256 === approvedSha256 &&
          fresh.jobObjectSha256 === record.jobObjectSha256 &&
          fresh.stopSha256 === record.stopSha256 &&
          fresh.policyStillInstalled === true &&
          fresh.accountReserved === true &&
          fresh.helperInventoryComplete === true &&
          fresh.custodyStillHeld === true &&
          hash(fresh.nativeEventSha256) &&
          dense(fresh.helpersSettled, 32).length ===
            record.helpers.length - 1 &&
          record.helpers
            .slice(0, -1)
            .every(
              (entry) =>
                fresh.helpersSettled.filter((identity) =>
                  sameWindowsIdentity(identity, entry.identity),
                ).length === 1,
            ),
      );
      const census = assessWindowsDomain(
        fresh.enumeration,
        record.accountSid,
        record.jobObjectSha256,
        record.jobPresent,
      );
      requireWindows(
        census.every(
          (entry) =>
            entry.signaled ||
            !signaled.some((identity) =>
              sameWindowsIdentity(identity, entry.identity),
            ),
        ),
      );
      if (census.some((entry) => !entry.signaled)) continue;
      requireWindows(
        fresh.knownProcessHandlesSignaled === true &&
          fresh.holderInventoryComplete === true &&
          (record.jobPresent
            ? fresh.onlyRecoveryHolder === true
            : fresh.jobHandleHeld === false && fresh.jobHolders === 0),
      );
      record.freshVerifier = freshIdentity;
      record.noLiveMembers = true;
      record.nativeEventSha256 = fresh.nativeEventSha256;
      record.phase = "custody-settlement";
      await receipt();
      const settled = await wait(
        effects.settleCustody(
          structuredClone(request),
          structuredClone(record),
        ),
      );
      verifier(settled.verifier, true);
      requireWindows(
        settled.independent === true &&
          settled.requestSha256 === approvedSha256 &&
          sameWindowsIdentity(settled.custodian, custodian.identity) &&
          settled.settled === true &&
          settled.jobHolders === 0 &&
          settled.policyStillInstalled === true &&
          settled.reservation === "RETAINED",
      );
      record.helpersSettled = true;
      record.independent = true;
      record.status = "RETIRED";
      record.phase = "retired";
      await wait(save());
      return structuredClone(record);
    }
    throw new Error("Windows retirement work exhausted");
  } catch {
    failed = true;
    abort();
    record.status = "FAIL";
    record.noLiveMembers = false;
    record.helpersSettled = false;
    await save();
    return structuredClone(record);
  } finally {
    cancel(timer);
  }
}
