import {
  closed,
  dense,
  digest,
  hash,
  requireWindows,
  sid,
  systemIdentity,
  sameWindowsIdentity,
  WINDOWS_PROCESS_LIMIT,
  WINDOWS_ARGUMENT_PARSER,
  windowsAccountName,
} from "./protocol.js";

const DENIED_LOGONS = Object.freeze([
  "interactive",
  "network",
  "remote-interactive",
  "service",
]);
function object(value) {
  requireWindows(
    value &&
      typeof value.volumeSerial === "string" &&
      /^[0-9a-f]{16}$/u.test(value.volumeSerial) &&
      typeof value.fileId === "string" &&
      /^[0-9a-f]{32}$/u.test(value.fileId) &&
      value.ownerSid === "S-1-5-18" &&
      value.noReparse === true &&
      value.exclusiveParents === true &&
      value.protectedDacl === true &&
      value.privateDacl === true &&
      hash(value.daclSha256),
  );
  return value.volumeSerial + ":" + value.fileId;
}
function account(value, request, accountSid) {
  requireWindows(
    value &&
      value.name === windowsAccountName(request.nonce) &&
      sid(value.sid) === accountSid &&
      value.restrictingSid === request.restrictingSid &&
      value.sid !== value.restrictingSid &&
      value.restrictingSidExclusive === true &&
      value.fresh === true &&
      value.nonLogin === true &&
      value.passwordPrivate === true &&
      value.batchOnly === true &&
      dense(value.ordinaryGroups, 32).length === 0 &&
      JSON.stringify(dense(value.deniedLogons, 4).sort()) ===
        JSON.stringify(DENIED_LOGONS),
  );
}
function job(value, request, payload, prior = null) {
  requireWindows(
    value &&
      value.name === "Local\\NativeProof-" + request.nonce &&
      hash(value.heldObjectSha256) &&
      value.sameHeldObject === true &&
      value.protectedDacl === true &&
      value.systemOnlyDacl === true &&
      value.inheritable === false &&
      value.breakaway === false &&
      value.silentBreakaway === false &&
      value.killOnLastClose === true &&
      value.processLimit === WINDOWS_PROCESS_LIMIT &&
      value.uiRestrictions === 255 &&
      value.creationTimeAdmission === true &&
      value.member === (payload !== null) &&
      (!prior || value.heldObjectSha256 === prior.heldObjectSha256),
  );
}
function verifier(value, record) {
  const identity = systemIdentity(value);
  requireWindows(
    record.helpers.some(
      (entry) =>
        entry.role === "verifier" &&
        sameWindowsIdentity(entry.identity, identity),
    ),
  );
}
export function assertWindowsPolicy(value, request, record) {
  requireWindows(
    value &&
      value.installed === true &&
      value.compositionSha256 === request.bindings.policy &&
      hash(value.receiptSha256) &&
      (!record.policyReceiptSha256 ||
        value.receiptSha256 === record.policyReceiptSha256) &&
      value.wfpInstalled === true &&
      value.filesystemInstalled === true &&
      value.effectiveGrantsMatchManifest === true &&
      value.hostDelegationDenied === true &&
      value.foreignHandlesDenied === true &&
      value.credentialsProtected === true &&
      value.checkoutProtected === true &&
      value.providersExcluded === true &&
      value.inheritanceReviewed === true,
  );
}
/** These snapshots are independent handle-based native reads. Job names and
 * launcher frames alone confer no object, token, DACL or policy authority. */
export function assertWindowsSetup(value, request, record) {
  requireWindows(
    value &&
      value.independent === true &&
      value.requestSha256 === record.requestSha256 &&
      hash(value.nativeEventSha256) &&
      sameWindowsIdentity(value.helper, record.helpers[0].identity) &&
      value.account.sid === record.accountSid,
  );
  verifier(value.verifier, record);
  account(value.account, request, record.accountSid);
  for (const name of ["custody", "storage", "workspace"])
    requireWindows(
      object(value[name]) &&
        value[name].path === request[name] &&
        value[name].systemOnlyDacl === true,
    );
  requireWindows(
    new Set([
      object(value.custody),
      object(value.storage),
      object(value.workspace),
    ]).size === 3,
  );
  job(value.job, request, null);
  requireWindows(
    value.desktop &&
      value.desktop.station === "np_" + request.nonce &&
      value.desktop.name === "payload" &&
      value.desktop.noninteractive === true &&
      value.desktop.protectedDacl === true &&
      value.desktop.privateDacl === true &&
      value.desktop.foreignHandles === 0 &&
      value.desktop.inheritable === false &&
      hash(value.desktop.nativeObjectSha256),
  );
  return value;
}
export function assertWindowsAuthority(value, request, record) {
  requireWindows(
    value &&
      value.independent === true &&
      value.requestSha256 === record.requestSha256 &&
      hash(value.nativeEventSha256) &&
      sameWindowsIdentity(value.helper, record.helpers[0].identity) &&
      sameWindowsIdentity(value.payload, record.payload) &&
      value.suspended === true &&
      value.threadSuspendCount === 1 &&
      value.processProtectedDacl === true &&
      value.threadProtectedDacl === true &&
      value.processSystemOnlyDacl === true &&
      value.threadSystemOnlyDacl === true &&
      value.account.sid === record.accountSid,
  );
  verifier(value.verifier, record);
  account(value.account, request, record.accountSid);
  for (const name of ["custody", "storage", "workspace"])
    requireWindows(
      object(value[name]) === object(record.setup[name]) &&
        value[name].path === request[name],
    );
  requireWindows(
    value.cwd === request.workspace &&
      value.cwdIdentity === object(value.workspace) &&
      value.custody.systemOnlyDacl === true,
  );
  job(value.job, request, record.payload, record.setup.job);
  requireWindows(
    JSON.stringify(value.desktop) === JSON.stringify(record.setup.desktop),
  );
  const token = value.token;
  closed(token, [
    "userSid",
    "restrictedSids",
    "privileges",
    "enabledGroups",
    "integritySid",
    "sessionId",
    "tokenId",
    "authenticationId",
    "primary",
    "virtualized",
    "writeRestricted",
  ]);
  requireWindows(
    token.userSid === record.accountSid &&
      JSON.stringify(dense(token.restrictedSids, 8)) ===
        JSON.stringify([request.restrictingSid]) &&
      dense(token.privileges, 64).length === 0 &&
      dense(token.enabledGroups, 128).length === 0 &&
      token.integritySid === "S-1-16-4096" &&
      token.sessionId === 0 &&
      token.primary === true &&
      token.virtualized === false &&
      token.writeRestricted === false &&
      [token.tokenId, token.authenticationId].every(
        (id) => typeof id === "string" && /^[0-9a-f]{16}$/u.test(id),
      ),
  );
  requireWindows(
    value.handles &&
      value.handles.explicitList === true &&
      value.handles.count === 2 &&
      value.handles.kinds === "stdin-read,stdout-stderr-write" &&
      value.handles.foreign === 0 &&
      value.handles.token === 0 &&
      value.handles.job === 0 &&
      value.handles.hostService === 0,
  );
  for (const key of ["launcher", "executable"]) {
    const image = value[key];
    object(image);
    requireWindows(
      image.path === request[key].path &&
        image.links === 1 &&
        image.sha256 === request[key].sha256 &&
        image.signatureSha256 === request[key].signatureSha256 &&
        image.authenticode === true &&
        image.architecture === "x64" &&
        image.loaderSha256 === request.bindings.closure &&
        image.untrustedWritable === false,
    );
  }
  requireWindows(
    value.launcher.systemOnlyDacl === true &&
      value.policyFile.systemOnlyDacl === true &&
      value.executable.parser === WINDOWS_ARGUMENT_PARSER &&
      value.executable.parserVerified === true &&
      object(value.policyFile) &&
      value.policyFile.path === request.policy.path &&
      value.policyFile.sha256 === request.policy.sha256 &&
      value.policyFile.untrustedWritable === false,
  );
  assertWindowsPolicy(value.policy, request, record);
  return value;
}
export function assertWindowsReceipt(value, record) {
  requireWindows(
    value &&
      value.independent === true &&
      value.immutable === true &&
      value.sha256 === digest(JSON.stringify(record) + "\n") &&
      hash(value.receiptSha256),
  );
  verifier(value.verifier, record);
}
