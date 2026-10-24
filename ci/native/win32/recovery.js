import {
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsArguments,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
  sid,
  windowsLaunchDigest,
  windowsAccountName,
  WINDOWS_PROCESS_LIMIT,
} from "./protocol.js";

export function windowsCustodyObject(value, path) {
  requireWindows(
    value &&
      value.path === path &&
      value.ownerSid === "S-1-5-18" &&
      value.protectedDacl === true &&
      value.systemOnlyDacl === true &&
      value.noReparse === true &&
      value.exclusiveParents === true &&
      hash(value.daclSha256) &&
      typeof value.volumeSerial === "string" &&
      /^[0-9a-f]{16}$/u.test(value.volumeSerial) &&
      typeof value.fileId === "string" &&
      /^[0-9a-f]{32}$/u.test(value.fileId),
  );
  return value.volumeSerial + ":" + value.fileId;
}

/** Protected native readers supply canonical bytes and held DACL/file identities.
 * Node path reads cannot establish Windows custody or principal authority. */
export function assessWindowsRecovery(value, input, approvedSha256) {
  const request = normalizeWindowsLaunch(input),
    receipt = value?.receipt;
  requireWindows(
    hash(approvedSha256) &&
      receipt &&
      receipt.schemaVersion === 1 &&
      receipt.candidateSha === request.candidateSha &&
      receipt.nonce === request.nonce &&
      receipt.requestSha256 === approvedSha256 &&
      receipt.reservation === "RETAINED" &&
      receipt.admission === "possible" &&
      ["RUNNING", "ADMITTED", "FAIL"].includes(receipt.status) &&
      windowsLaunchDigest(
        receipt.request,
        normalizeWindowsArguments(receipt.arguments),
      ) === approvedSha256 &&
      JSON.stringify(normalizeWindowsLaunch(receipt.request)) ===
        JSON.stringify(request) &&
      Buffer.byteLength(JSON.stringify(receipt) + "\n") <= 1048576 &&
      value.receiptSha256 === digest(JSON.stringify(receipt) + "\n"),
  );
  const custodyIdentity = windowsCustodyObject(value.custody, request.custody);
  windowsCustodyObject(
    value.receiptFile,
    request.custody + "\\windows-admission.json",
  );
  requireWindows(
    value.receiptFile.immutable === true &&
      value.receiptFile.links === 1 &&
      value.receiptFile.sha256 === value.receiptSha256,
  );
  if (!receipt.setup || !receipt.accountSid || !receipt.helpers?.length)
    return {
      missingInputs: ["windows-protected-account-job-admission-binding"],
    };
  const { account, job } = receipt.setup;
  requireWindows(
    account.name === windowsAccountName(request.nonce) &&
      sid(account.sid) === receipt.accountSid &&
      /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(account.sid) &&
      account.sid !== request.restrictingSid &&
      account.restrictingSid === request.restrictingSid &&
      account.restrictingSidExclusive === true &&
      account.fresh === true &&
      account.nonLogin === true &&
      account.passwordPrivate === true &&
      account.batchOnly === true &&
      dense(account.ordinaryGroups, 32).length === 0 &&
      JSON.stringify(dense(account.deniedLogons, 4).sort()) ===
        JSON.stringify([
          "interactive",
          "network",
          "remote-interactive",
          "service",
        ]) &&
      job.name === "Local\\NativeProof-" + request.nonce &&
      hash(job.heldObjectSha256) &&
      job.systemOnlyDacl === true &&
      job.protectedDacl === true &&
      job.inheritable === false &&
      job.breakaway === false &&
      job.silentBreakaway === false &&
      job.killOnLastClose === true &&
      job.creationTimeAdmission === true &&
      job.processLimit === WINDOWS_PROCESS_LIMIT &&
      job.uiRestrictions === 255,
  );
  const helpers = dense(receipt.helpers, 16).map((entry) => {
    requireWindows(
      ["launcher", "verifier", "wfp"].includes(entry.role) &&
        hash(entry.imageSha256) &&
        hash(entry.sourceSha256),
    );
    return { ...entry, identity: systemIdentity(entry.identity) };
  });
  requireWindows(
    helpers[0].role === "launcher" &&
      helpers[0].imageSha256 === request.launcher.sha256,
  );
  const members = receipt.payload
    ? [normalizeWindowsIdentity(receipt.payload)]
    : [];
  const previous = value.previousRetirement;
  if (previous !== undefined && previous !== null) {
    requireWindows(
      value.previousSha256 === digest(JSON.stringify(previous) + "\n") &&
        Buffer.byteLength(JSON.stringify(previous) + "\n") <= 1048576 &&
        previous.schemaVersion === 1 &&
        previous.requestSha256 === approvedSha256 &&
        previous.candidateSha === request.candidateSha &&
        previous.nonce === request.nonce &&
        previous.accountSid === account.sid &&
        previous.jobObjectSha256 === job.heldObjectSha256 &&
        previous.reservation === "RETAINED",
    );
    windowsCustodyObject(
      value.previousFile,
      request.custody + "\\windows-retirement.json",
    );
    requireWindows(
      value.previousFile.immutable === true &&
        value.previousFile.links === 1 &&
        value.previousFile.sha256 === value.previousSha256,
    );
    for (const entry of dense(previous.helpers, 32)) {
      requireWindows(
        ["launcher", "verifier", "wfp", "recovery"].includes(entry.role) &&
          hash(entry.imageSha256) &&
          hash(entry.sourceSha256),
      );
      const identity = systemIdentity(entry.identity);
      if (!helpers.some((item) => sameWindowsIdentity(item.identity, identity)))
        helpers.push({ ...entry, identity });
    }
    for (const identity of dense(previous.members, 256).map(
      normalizeWindowsIdentity,
    ))
      if (!members.some((item) => sameWindowsIdentity(item, identity)))
        members.push(identity);
  }
  requireWindows(
    helpers.length <= 32 &&
      members.length <= 256 &&
      new Set(helpers.map((entry) => entry.identity.pid)).size ===
        helpers.length &&
      members.every(
        (identity) =>
          identity.userSid === account.sid &&
          identity.sessionId === 0 &&
          !helpers.some((entry) => entry.identity.pid === identity.pid),
      ),
  );
  return {
    accountSid: account.sid,
    job,
    helpers,
    members,
    custodyIdentity,
    receiptSha256: value.receiptSha256,
  };
}

/** A complete native account-principal census also covers lost/nested Jobs.
 * Unknown identities, inaccessible tokens and truncated views retain exclusion. */
export function assessWindowsDomain(
  value,
  accountSid,
  jobObjectSha256,
  jobPresent,
) {
  requireWindows(
    value &&
      value.complete === true &&
      value.accountSid === accountSid &&
      value.accountReservationVerified === true &&
      value.capacity === WINDOWS_PROCESS_LIMIT + 1 &&
      value.truncated === false &&
      hash(value.nativeEventSha256),
  );
  const entries = dense(value.processes, WINDOWS_PROCESS_LIMIT).map((entry) => {
    const identity = normalizeWindowsIdentity(entry.identity);
    requireWindows(
      identity.userSid === accountSid &&
        identity.sessionId === 0 &&
        entry.heldProcessVerified === true &&
        typeof entry.signaled === "boolean" &&
        (!jobPresent ||
          (entry.inJob === true && entry.jobObjectSha256 === jobObjectSha256)),
    );
    return { identity, signaled: entry.signaled };
  });
  requireWindows(
    new Set(entries.map((entry) => entry.identity.pid)).size === entries.length,
  );
  return entries;
}

export function assertWindowsRetirement(
  value,
  input,
  approvedSha256,
  accountSid,
  jobObjectSha256,
) {
  const request = normalizeWindowsLaunch(input),
    verifier = systemIdentity(value?.freshVerifier);
  requireWindows(
    value.status === "RETIRED" &&
      value.independent === true &&
      value.schemaVersion === 1 &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.requestSha256 === approvedSha256 &&
      value.accountSid === accountSid &&
      value.jobObjectSha256 === jobObjectSha256 &&
      value.noLiveMembers === true &&
      value.helpersSettled === true &&
      value.reservation === "RETAINED" &&
      hash(value.nativeEventSha256) &&
      !dense(value.helpers, 32).some(
        (entry) => entry.identity.pid === verifier.pid,
      ) &&
      !dense(value.members, 256).some(
        (identity) => identity.pid === verifier.pid,
      ),
  );
  return verifier;
}
