import {
  NativeEvidenceError,
  LINUX_OWNERSHIP_CHECK_IDS,
  LINUX_POLICY_ID,
} from "../index.js";
import { ACCESS_PROFILES } from "./profiles.js";

export const LINUX_OWNERSHIP_CASES = Object.freeze([
  "argv",
  "cancel",
  "owner-loss",
  "supervisor-loss",
  "launcher-loss",
]);
export { LINUX_OWNERSHIP_CHECK_IDS, LINUX_POLICY_ID };
const PROOF_CASES = [...LINUX_OWNERSHIP_CASES, ...ACCESS_PROFILES];
const RECEIPT_CASES = [...PROOF_CASES, "file-helper"];
const DIGEST = /^[a-f0-9]{64}$/u;
const BOOT = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const NAMESPACE = /^pid:\[[1-9][0-9]*\]$/u;
const DEADLINE = 30000;

function requireValue(value) {
  if (!value) throw new NativeEvidenceError();
}

function object(value, keys) {
  requireValue(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length,
  );
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    requireValue(descriptor?.enumerable && Object.hasOwn(descriptor, "value"));
  }
}

function list(value, maximum) {
  requireValue(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  for (let i = 0; i < value.length; i++)
    requireValue(
      Object.hasOwn(
        Object.getOwnPropertyDescriptor(value, String(i)) ?? {},
        "value",
      ),
    );
}

function pid(value) {
  requireValue(Number.isSafeInteger(value) && value > 0 && value <= 2147483647);
  return value;
}

function identity(value) {
  object(value, ["bootId", "startTicks"]);
  requireValue(
    typeof value.bootId === "string" &&
      BOOT.test(value.bootId) &&
      typeof value.startTicks === "string" &&
      /^(?:0|[1-9][0-9]{0,31})$/u.test(value.startTicks),
  );
  return { bootId: value.bootId, startTicks: value.startTicks };
}

export function sameLinuxIdentity(left, right) {
  return (
    left != null &&
    right != null &&
    left.bootId === right.bootId &&
    left.startTicks === right.startTicks
  );
}

export function normalizeLinuxReceipt(value) {
  object(value, [
    "schemaVersion",
    "candidateSha",
    "caseId",
    "nonce",
    "policyDigest",
    "executableDigest",
    "isolatedNamespace",
    "hostSession",
    "parentNamespaceId",
    "init",
    "launcher",
    "controller",
    "admission",
  ]);
  requireValue(
    value.schemaVersion === 1 &&
      typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      RECEIPT_CASES.includes(value.caseId) &&
      typeof value.nonce === "string" &&
      BOOT.test(value.nonce) &&
      typeof value.policyDigest === "string" &&
      DIGEST.test(value.policyDigest) &&
      typeof value.executableDigest === "string" &&
      DIGEST.test(value.executableDigest) &&
      value.isolatedNamespace === true &&
      value.hostSession === false &&
      typeof value.parentNamespaceId === "string" &&
      NAMESPACE.test(value.parentNamespaceId),
  );
  object(value.init, ["pid", "identity", "namespaceId", "nspid"]);
  list(value.init.nspid, 32);
  const init = {
    pid: pid(value.init.pid),
    identity: identity(value.init.identity),
    namespaceId: value.init.namespaceId,
    nspid: [...value.init.nspid],
  };
  init.nspid.forEach(pid);
  requireValue(
    init.nspid.length >= 2 &&
      init.nspid[0] === init.pid &&
      init.nspid.at(-1) === 1 &&
      typeof init.namespaceId === "string" &&
      NAMESPACE.test(init.namespaceId) &&
      init.namespaceId !== value.parentNamespaceId,
  );
  const processes = {};
  for (const name of ["launcher", "controller"]) {
    object(value[name], ["pid", "identity"]);
    processes[name] = {
      pid: pid(value[name].pid),
      identity: identity(value[name].identity),
    };
    requireValue(
      processes[name].identity.bootId === init.identity.bootId &&
        processes[name].pid !== init.pid,
    );
  }
  requireValue(processes.launcher.pid !== processes.controller.pid);
  object(value.admission, [
    "processIdentity",
    "namespaceId",
    "launchCutoff",
    "ancestryBaseline",
    "controlGroup",
  ]);
  const admission = {
    processIdentity: identity(value.admission.processIdentity),
    namespaceId: value.admission.namespaceId,
    launchCutoff: identity(value.admission.launchCutoff),
    ancestryBaseline: [],
    controlGroup: value.admission.controlGroup,
  };
  requireValue(
    sameLinuxIdentity(admission.processIdentity, init.identity) &&
      sameLinuxIdentity(admission.launchCutoff, init.identity) &&
      admission.namespaceId === init.namespaceId &&
      typeof admission.controlGroup === "string" &&
      DIGEST.test(admission.controlGroup),
  );
  list(value.admission.ancestryBaseline, 4096);
  let previous = 0;
  for (const entry of value.admission.ancestryBaseline) {
    object(entry, ["bootId", "pid", "startTicks"]);
    const normalized = {
      ...identity({ bootId: entry.bootId, startTicks: entry.startTicks }),
      pid: pid(entry.pid),
    };
    requireValue(
      normalized.pid > previous &&
        normalized.bootId === init.identity.bootId &&
        BigInt(normalized.startTicks) <=
          BigInt(admission.launchCutoff.startTicks),
    );
    previous = normalized.pid;
    admission.ancestryBaseline.push(normalized);
  }
  requireValue(admission.ancestryBaseline.length > 0);
  return { ...value, init, ...processes, admission };
}

/** Absence is a proc-directory ENOENT/ESRCH observation, never a null identity
 * read. A replaced, inaccessible, or still-live init retains exclusion. */
export function assessLinuxRetirement(input, observation) {
  const receipt = normalizeLinuxReceipt(input);
  object(observation, [
    "bootId",
    "observerNamespaceId",
    "procVisible",
    "before",
    "after",
  ]);
  const retired =
    observation.bootId === receipt.init.identity.bootId &&
    observation.observerNamespaceId === receipt.parentNamespaceId &&
    observation.procVisible === true &&
    observation.before === "absent" &&
    observation.after === "absent";
  return {
    status: retired ? "RETIRED" : "RETAINED",
    independent: retired,
    emergencyCleanup: false,
  };
}

/** Admission/probe effects enforce one non-resetting deadline; fresh cleanup
 * has its own bound. Release and faults require protected acknowledged barriers. */
export async function runLinuxOwnershipCase(caseId, effects) {
  requireValue(PROOF_CASES.includes(caseId));
  const notRun = () => ({
    status: "NOT_RUN",
    elapsedMs: null,
    deadlineMs: DEADLINE,
    reason: "missing-input",
  });
  const phases = { setup: notRun(), probe: notRun(), cleanup: notRun() };
  let receipt = null;
  let stage = "setup";
  let started = effects.now();
  const admissionStarted = started;
  let observations = [];
  let settlement = {
    status: "RETAINED",
    independent: false,
    emergencyCleanup: false,
  };
  const assertAdmissionDeadline = () =>
    requireValue(effects.now() - admissionStarted < DEADLINE);
  const pass = () => {
    const elapsedMs = Math.ceil(effects.now() - started);
    requireValue(elapsedMs >= 0 && elapsedMs <= DEADLINE);
    if (stage !== "cleanup") assertAdmissionDeadline();
    phases[stage] = {
      status: "PASS",
      elapsedMs,
      deadlineMs: DEADLINE,
      reason: null,
    };
  };
  try {
    receipt = normalizeLinuxReceipt(await effects.admit());
    requireValue(receipt.caseId === caseId);
    await effects.confirmReceipt(receipt);
    await effects.acknowledgeAdmission();
    await effects.ready();
    pass();
    stage = "probe";
    started = effects.now();
    assertAdmissionDeadline();
    await effects.release();
    observations = await effects.observe(receipt);
    requireValue(
      Array.isArray(observations) &&
        observations.length > 0 &&
        observations.every(
          (entry) =>
            entry.matched === true &&
            entry.positiveControl === true &&
            entry.attempted === true &&
            entry.sentinelsUnchanged === true,
        ),
    );
    const acknowledgement = await effects.armFault(caseId);
    requireValue(
      acknowledgement?.caseId === caseId &&
        acknowledgement.nonce === receipt.nonce &&
        acknowledgement.armed === true,
    );
    assertAdmissionDeadline();
    await effects.fireFault(caseId);
    await effects.settle();
    pass();
    stage = "cleanup";
    started = effects.now();
    settlement = await effects.verify(receipt);
    requireValue(
      settlement.status === "RETIRED" &&
        settlement.independent === true &&
        settlement.emergencyCleanup === false,
    );
    await effects.cleanup();
    pass();
    return {
      caseId,
      status: "PASS",
      reason: null,
      phases,
      observations,
      settlement,
    };
  } catch {
    const elapsedMs = Math.ceil(effects.now() - started);
    const reason =
      elapsedMs > DEADLINE ||
      (stage !== "cleanup" && effects.now() - admissionStarted >= DEADLINE)
        ? "deadline"
        : `${stage}-failed`;
    phases[stage] = { status: "FAIL", elapsedMs, deadlineMs: DEADLINE, reason };
    // Emergency retirement is attempted, but never repairs this failed case.
    settlement = {
      status: "RETAINED",
      independent: false,
      emergencyCleanup: true,
    };
    const cleanupStarted = effects.now();
    let cleaned = false;
    try {
      await effects.emergencyStop();
      if (receipt !== null) {
        const verified = await effects.verify(receipt);
        if (
          verified.status === "RETIRED" &&
          verified.independent === true &&
          verified.emergencyCleanup === false
        )
          settlement = { ...verified, emergencyCleanup: true };
      }
      if (settlement.status === "RETIRED") {
        await effects.cleanup();
        cleaned = true;
      }
    } catch {
      /* Retain protected storage and exclusion when settlement is unknown. */
    }
    const cleanupElapsed = Math.ceil(effects.now() - cleanupStarted);
    if (stage !== "cleanup")
      phases.cleanup = {
        status: cleaned && cleanupElapsed <= DEADLINE ? "PASS" : "FAIL",
        elapsedMs: cleanupElapsed,
        deadlineMs: DEADLINE,
        reason:
          settlement.status !== "RETIRED"
            ? "unretired"
            : cleanupElapsed > DEADLINE
              ? "deadline"
              : !cleaned
                ? "cleanup-failed"
                : null,
      };
    return {
      caseId,
      status: "FAIL",
      reason: settlement.status === "RETIRED" ? reason : "unretired",
      phases,
      observations,
      settlement,
    };
  }
}
