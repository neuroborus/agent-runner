import { performance } from "node:perf_hooks";
import { isIP } from "node:net";
import {
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsLaunch,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
  windowsLaunchDigest,
} from "./protocol.js";
import { buildWindowsPolicy, assertWindowsPolicyToken } from "./policy.js";
import {
  assertWindowsPolicyInstallation,
  assertWindowsPolicySnapshot,
  assertWindowsPolicyHelpersRetired,
  windowsPolicyCustodyDigest,
} from "./policy-effects.js";
import { assertWindowsRetirement } from "./recovery.js";

const FILE_DENIALS = [
  "metadata-write",
  "pointer-write",
  "pointer-delete",
  "pointer-replace",
  "parent-delete",
  "parent-replace",
  "custody",
  "checkout",
  "configuration",
  "credentials",
  "registry",
  "outside-write",
];
const IPC_DENIALS = ["host-pipe", "alpc", "rpc", "com", "wmi", "delegation"];
const NETWORK_DENIALS = [
  "host-listener",
  "wildcard-listener",
  "host-network",
  "cross-allocation",
  "foreign-sender",
];
export const WINDOWS_ACCESS_DENIALS = Object.freeze([
  ...FILE_DENIALS,
  ...IPC_DENIALS,
  ...["v4", "v6"].flatMap((family) =>
    ["tcp", "udp"].flatMap((protocol) =>
      NETWORK_DENIALS.map((name) => `${name}-${family}-${protocol}`),
    ),
  ),
]);
const FILE_TARGETS = Object.freeze({
  "metadata-write": "metadata",
  "pointer-write": "pointer",
  "pointer-delete": "pointer",
  "pointer-replace": "pointer",
  "parent-delete": "workspace",
  "parent-replace": "workspace",
  custody: "custody",
  checkout: "checkout",
  configuration: "configuration",
  credentials: "credentials",
  registry: "registry",
  "outside-write": "outside",
});
const objectIdentity = (entry) =>
  entry.descriptor.name === "registry"
    ? entry.registryIdentitySha256
    : digest(entry.volumeSerial + ":" + entry.fileId);

function state(value) {
  requireWindows(
    value &&
      hash(value.identitySha256) &&
      hash(value.bytesSha256) &&
      hash(value.nativeEventSha256),
  );
  return value.identitySha256 + ":" + value.bytesSha256;
}
function owned(identity, plan) {
  identity = normalizeWindowsIdentity(identity);
  requireWindows(
    identity.userSid === plan.value.accountSid && identity.sessionId === 0,
  );
  return identity;
}
function nativeEvent(event, plan) {
  requireWindows(
    event?.independent === true &&
      event.nonce === plan.value.request.nonce &&
      hash(event.nativeEventSha256) &&
      event.timedOut === false &&
      event.lossCount === 0 &&
      event.identityVerified === true,
  );
}

function accessDenied(entry) {
  if (entry.caseId === "com") return entry.nativeCode === 0x80070005;
  if (entry.caseId === "wmi")
    return [0x80070005, 0x80041003].includes(entry.nativeCode);
  return entry.nativeCode === 5;
}

function networkDenial(entry, plan, installation, actor) {
  const family = entry.caseId.includes("-v4-") ? "v4" : "v6",
    protocol = entry.caseId.endsWith("-tcp") ? "tcp" : "udp",
    loop = family === "v4" ? "127.0.0.1" : "::1",
    wildcard = family === "v4" ? "0.0.0.0" : "::",
    attempt = entry.attempt,
    endpoint = entry.control.endpoint;
  nativeEvent(attempt, plan);
  requireWindows(
    sameWindowsIdentity(attempt.identity, actor) &&
      attempt.protocol === protocol &&
      hash(attempt.socketIdentitySha256) &&
      endpoint?.identityVerified === true &&
      hash(endpoint.socketIdentitySha256) &&
      endpoint.protocol === protocol &&
      endpoint.address === attempt.remoteAddress &&
      endpoint.port === attempt.remotePort &&
      sameWindowsIdentity(
        endpoint.identity,
        entry.caseId.startsWith("foreign-sender-")
          ? entry.protectedIdentity
          : entry.control.identity,
      ),
  );
  for (const side of ["local", "remote"]) {
    const address = attempt[side + "Address"],
      port = attempt[side + "Port"];
    requireWindows(
      isIP(address) === (family === "v4" ? 4 : 6) &&
        (family === "v4" ||
          new URL(`http://[${address}]/`).hostname === `[${address}]`) &&
        Number.isInteger(port) &&
        port >= 1024 &&
        port <= 65535,
    );
  }
  const hostNetwork = entry.caseId.startsWith("host-network-");
  const routed = (address) =>
    address !== wildcard &&
    address !== loop &&
    !address.startsWith("127.") &&
    !address.startsWith("::ffff:");
  requireWindows(
    (hostNetwork
      ? routed(endpoint.address) && routed(attempt.localAddress)
      : attempt.localAddress === loop && endpoint.address === loop) &&
      endpoint.bindAddress ===
        (entry.caseId.startsWith("wildcard-listener-")
          ? wildcard
          : endpoint.address),
  );
  if (entry.caseId.startsWith("foreign-sender-"))
    requireWindows(
      plan.value.endpoints.some(
        (reserved) =>
          reserved.family === family &&
          reserved.protocol === protocol &&
          [reserved.clientPort, reserved.serverPort].includes(endpoint.port),
      ),
    );
  if (entry.caseId.startsWith("cross-allocation-"))
    requireWindows(
      /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(
        endpoint.identity.userSid,
      ) &&
        entry.control.tokenReviewed === true &&
        entry.control.accountReservationVerified === true,
    );
  const filter = installation.effective.wfp.filters.find(
      (item) => item.id === entry.filterId,
    ),
    principal = normalizeWindowsIdentity(entry.filterIdentity),
    connect = entry.layer?.includes("CONNECT");
  // Connect identifies the sender; receive/accept identifies the listener.
  // SID equality alone cannot join a drop from a different owned process.
  requireWindows(
    filter?.descriptor.action === "BLOCK" &&
      entry.wfpAction === "DROP" &&
      entry.protocol === protocol &&
      entry.layer === filter.descriptor.layer &&
      entry.layer.endsWith(family.toUpperCase()) &&
      entry.localPrincipalSid === principal.userSid &&
      sameWindowsIdentity(principal, connect ? actor : endpoint.identity) &&
      entry.socketIdentityVerified === true &&
      entry.socketIdentitySha256 ===
        (connect
          ? attempt.socketIdentitySha256
          : endpoint.socketIdentitySha256) &&
      (filter.descriptor.principal === null ||
        filter.descriptor.principal === principal.userSid) &&
      Object.entries(filter.descriptor.conditions).every(
        ([key, expected]) => entry[key] === expected,
      ),
  );
  for (const field of ["Address", "Port"])
    requireWindows(
      entry["local" + field] ===
        attempt[(connect ? "local" : "remote") + field] &&
        entry["remote" + field] ===
          attempt[(connect ? "remote" : "local") + field],
    );
}

/** Each denial joins a reached native operation, a beforehand acknowledged
 * reachable control and a separate unchanged identity/byte observation. */
export function assertWindowsAccessObservation(
  value,
  input,
  installation,
  payload,
  jobObjectSha256,
) {
  const plan = buildWindowsPolicy(input),
    { request } = plan.value;
  assertWindowsPolicyInstallation(installation, plan.value);
  nativeEvent(value, plan);
  systemIdentity(value.verifier);
  requireWindows(
    hash(jobObjectSha256) && value.jobObjectSha256 === jobObjectSha256,
  );
  const members = dense(value.members, 64),
    identities = new Set();
  requireWindows(members.length > 0);
  for (const member of members) {
    nativeEvent(member, plan);
    const identity = owned(member.identity, plan),
      key = JSON.stringify(identity);
    requireWindows(
      member.jobObjectSha256 === jobObjectSha256 &&
        member.creationTimeJobVerified === true &&
        member.heldIdentityVerified === true &&
        !identities.has(key),
    );
    systemIdentity(member.verifier);
    assertWindowsPolicyToken(member.token, plan.value);
    identities.add(key);
  }
  const participant = (value) => {
    const identity = owned(value, plan);
    requireWindows(identities.has(JSON.stringify(identity)));
    return identity;
  };
  requireWindows(
    value.candidateSha === request.candidateSha &&
      value.compositionSha256 === plan.compositionSha256 &&
      sameWindowsIdentity(participant(value.identity), payload) &&
      value.privateChannelsOnly === true &&
      value.providersExcluded === true,
  );
  assertWindowsPolicyToken(value.token, plan.value);
  const read = value.read;
  const ownedFile = installation.effective.objects.find(
    (entry) => entry.descriptor.name === "owned",
  );
  nativeEvent(read, plan);
  participant(read.identity);
  requireWindows(
    read.allowed === true &&
      read.nativeCode === 0 &&
      read.bytes === request.nonce &&
      read.fileIdentitySha256 === objectIdentity(ownedFile),
  );
  const edit = value.edit;
  nativeEvent(edit, plan);
  participant(edit.identity);
  requireWindows(
    edit.before.identitySha256 === objectIdentity(ownedFile) &&
      edit.before.bytesSha256 === digest(request.nonce),
  );
  if (plan.value.profile === "read-only")
    requireWindows(
      edit.allowed === false &&
        edit.nativeCode === 5 &&
        state(edit.before) === state(edit.after),
    );
  else
    requireWindows(
      edit.allowed === true &&
        edit.nativeCode === 0 &&
        edit.bytes === request.nonce + "-owned-edit" &&
        edit.after.bytesSha256 === digest(edit.bytes) &&
        edit.before.identitySha256 === edit.after.identitySha256 &&
        state(edit.before) !== state(edit.after),
    );
  const denials = dense(value.denials, WINDOWS_ACCESS_DENIALS.length);
  requireWindows(
    denials.length === WINDOWS_ACCESS_DENIALS.length &&
      new Set(denials.map((entry) => entry.caseId)).size === denials.length,
  );
  for (const entry of denials) {
    nativeEvent(entry, plan);
    const network = NETWORK_DENIALS.some((name) =>
      entry.caseId.startsWith(name + "-"),
    );
    const foreignSender = entry.caseId.startsWith("foreign-sender-"),
      actor = normalizeWindowsIdentity(entry.identity);
    requireWindows(
      WINDOWS_ACCESS_DENIALS.includes(entry.caseId) &&
        (foreignSender
          ? actor.userSid !== plan.value.accountSid &&
            actor.userSid !== request.restrictingSid &&
            participant(entry.protectedIdentity)
          : participant(actor)) &&
        entry.attempted === true &&
        entry.allowed === false &&
        (network
          ? entry.nativeCode === 10013 ||
            entry.nativeCode === (entry.caseId.endsWith("-tcp") ? 10035 : 0)
          : accessDenied(entry)) &&
        state(entry.before) === state(entry.after),
    );
    const targetName = FILE_TARGETS[entry.caseId];
    if (targetName) {
      const target = installation.effective.objects.find(
        (object) => object.descriptor.name === targetName,
      );
      requireWindows(
        entry.target === target.descriptor.path &&
          entry.before.identitySha256 === objectIdentity(target),
      );
    }
    const control = entry.control;
    nativeEvent(control, plan);
    systemIdentity(control.verifier);
    const controller = normalizeWindowsIdentity(control.identity);
    requireWindows(
      control.ready === true &&
        control.reachable === true &&
        control.readyBeforeAttempt === true &&
        control.bytes === request.nonce &&
        control.targetIdentitySha256 === entry.before.identitySha256 &&
        (foreignSender
          ? controller.userSid === plan.value.accountSid &&
            participant(controller) &&
            control.privatePeer === true &&
            control.tokenReviewed === true
          : controller.userSid !== plan.value.accountSid &&
            controller.userSid !== request.restrictingSid) &&
        controller.pid !== payload.pid,
    );
    if (network) networkDenial(entry, plan, installation, actor);
  }
  const loopback = dense(value.loopback, 4);
  requireWindows(
    loopback.length === 4 &&
      new Set(loopback.map((entry) => entry.family + entry.protocol)).size ===
        4,
  );
  const sockets = new Set();
  for (const entry of loopback) {
    const endpoint = plan.value.endpoints.find(
      (item) =>
        item.family === entry.family && item.protocol === entry.protocol,
    );
    nativeEvent(entry, plan);
    requireWindows(
      endpoint &&
        entry.bytes === request.nonce &&
        entry.echo === request.nonce &&
        entry.readyBeforeAttempt === true,
    );
    const events = dense(entry.events, 4);
    requireWindows(
      events.length === 4 &&
        new Set(events.map((event) => event.leg + event.direction)).size === 4,
    );
    const reservation = installation.effective.endpoints.find(
      (item) =>
        item.endpoint.family === entry.family &&
        item.endpoint.protocol === entry.protocol,
    );
    for (const side of ["client", "server"]) {
      const identity = participant(entry[side]?.identity);
      requireWindows(
        entry[side]?.heldIdentityVerified === true &&
          entry[side].reservationIdentitySha256 ===
            reservation[side].reservationIdentitySha256 &&
          hash(entry[side].socketIdentitySha256) &&
          !sockets.has(entry[side].socketIdentitySha256) &&
          entry[side].userSid === identity.userSid &&
          JSON.stringify(entry[side].restrictedSids) ===
            JSON.stringify([request.restrictingSid]),
      );
      sockets.add(entry[side].socketIdentitySha256);
    }
    for (const event of events) {
      nativeEvent(event, plan);
      participant(event.identity);
      requireWindows(
        ["request", "return"].includes(event.leg) &&
          ["connect", "receive"].includes(event.direction) &&
          event.action === "PERMIT" &&
          event.localPrincipalSid === plan.value.accountSid &&
          event.socketIdentityVerified === true,
      );
      const flowReturn = entry.protocol === "tcp" && event.leg === "return";
      // A TCP response uses the already authorized flow. Correlate actual
      // return bytes/socket identity to its original ALE authorization; never
      // invent a second connect/accept event for an established connection.
      const connectLayer = (event.direction === "connect") !== flowReturn;
      const layer =
        "ALE_AUTH_" +
        (connectLayer ? "CONNECT" : "RECV_ACCEPT") +
        "_" +
        entry.family.toUpperCase();
      const clientLocal =
        (event.leg === "request") === (event.direction === "connect");
      const filter = installation.effective.wfp.filters.find(
        (item) => item.id === event.filterId,
      );
      const tuple = filter?.descriptor.conditions;
      requireWindows(
        event.authorization === (flowReturn ? "verified-flow" : "ale") &&
          (!flowReturn ||
            (event.flowAuthorizationVerified === true &&
              hash(event.flowIdentitySha256) &&
              events.some(
                (prior) =>
                  prior.leg === "request" &&
                  prior.flowIdentitySha256 === event.flowIdentitySha256 &&
                  prior.filterId === event.filterId,
              ))) &&
          JSON.stringify(event.restrictedSids) ===
            JSON.stringify([request.restrictingSid]) &&
          event.socketIdentitySha256 ===
            entry[clientLocal ? "client" : "server"].socketIdentitySha256 &&
          sameWindowsIdentity(
            event.identity,
            entry[clientLocal ? "client" : "server"].identity,
          ) &&
          filter?.descriptor.action === "PERMIT" &&
          filter.descriptor.layer === layer &&
          event.layer === layer &&
          tuple.protocol === entry.protocol &&
          tuple.localPort ===
            (clientLocal ? endpoint.clientPort : endpoint.serverPort) &&
          tuple.remotePort ===
            (clientLocal ? endpoint.serverPort : endpoint.clientPort) &&
          event.localPort === tuple.localPort &&
          event.remotePort === tuple.remotePort &&
          event.localAddress === tuple.localAddress &&
          event.remoteAddress === tuple.remoteAddress,
      );
    }
  }
  return value;
}

/** Owner/helper loss cases preserve persistent filters before fresh recovery.
 * Observations are corroboration of the reviewed native composition, not a
 * provider dispatch grant or a finite-fixture containment argument. */
export async function runWindowsAccessCase(
  input,
  effects,
  {
    fault = "none",
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const plan = buildWindowsPolicy(input),
    { request } = plan.value;
  requireWindows(
    ["none", "owner-loss", "helper-loss"].includes(fault) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    compositionSha256: plan.compositionSha256,
    fault,
    status: "BLOCKED",
    phase: "composition",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const name of [
    "prepare",
    "admit",
    "observe",
    "snapshot",
    "retire",
    ...(fault === "none" ? [] : ["armFault", "fireFault"]),
  ])
    if (typeof effects[name] !== "function")
      record.missingInputs.push("windows-access-" + name);
  let writes = Promise.resolve();
  const save = () => {
    const copy = structuredClone(record);
    writes = writes.then(
      () => effects.persist(copy),
      () => effects.persist(copy),
    );
    return writes;
  };
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const start = now();
  let expired = false,
    rejectDeadline;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  deadline.catch(() => {});
  const timer = schedule(() => {
    expired = true;
    rejectDeadline(new Error("Windows access deadline"));
  }, 60000);
  const wait = async (promise) => {
    const value = await Promise.race([promise, deadline]);
    requireWindows(!expired && now() >= start && now() - start < 60000);
    return structuredClone(value);
  };
  let admission;
  try {
    record.phase = "prepare-intent";
    await wait(save());
    const prepared = await wait(effects.prepare(structuredClone(plan)));
    requireWindows(
      prepared.independent === true &&
        prepared.completeCompositionReviewed === true &&
        prepared.profile === plan.value.profile &&
        prepared.reviewSha256 === plan.value.reviewSha256 &&
        prepared.disposable === plan.value.disposable &&
        prepared.controlsReady === true &&
        prepared.barriersAcknowledged === true &&
        hash(prepared.nativeEventSha256),
    );
    assertWindowsPolicyInstallation(prepared.installation, plan.value);
    if (fault !== "none") {
      requireWindows(prepared.ownerIdentityVerified === true);
      systemIdentity(prepared.owner);
    }
    record.phase = "admission-intent";
    await wait(save());
    admission = await wait(
      effects.admit(structuredClone(plan.value), structuredClone(prepared)),
    );
    requireWindows(
      admission.status === "ADMITTED" &&
        admission.candidateSha === request.candidateSha &&
        admission.nonce === request.nonce &&
        admission.accountSid === plan.value.accountSid &&
        JSON.stringify(normalizeWindowsLaunch(admission.request)) ===
          JSON.stringify(request) &&
        admission.requestSha256 ===
          windowsLaunchDigest(request, admission.arguments) &&
        admission.policyReceiptSha256 === prepared.installation.receiptSha256 &&
        admission.payload &&
        hash(admission.setup?.job?.heldObjectSha256),
    );
    owned(admission.payload, plan);
    record.phase = "observe-intent";
    await wait(save());
    record.observation = await wait(
      effects.observe(structuredClone(admission), structuredClone(prepared)),
    );
    assertWindowsAccessObservation(
      record.observation,
      plan.value,
      prepared.installation,
      admission.payload,
      admission.setup.job.heldObjectSha256,
    );
    if (fault !== "none") {
      const armed = await wait(
        effects.armFault(fault, structuredClone(admission)),
      );
      nativeEvent(armed, plan);
      const target = systemIdentity(armed.identity);
      requireWindows(
        armed.acknowledged === true &&
          armed.fault === fault &&
          armed.requestSha256 === admission.requestSha256 &&
          armed.heldIdentityVerified === true &&
          armed.signaled === false &&
          !sameWindowsIdentity(systemIdentity(armed.verifier), target) &&
          (fault === "owner-loss"
            ? sameWindowsIdentity(target, prepared.owner)
            : dense(admission.helpers, 16).some(
                (helper) =>
                  ["launcher", "account", "wfp"].includes(helper.role) &&
                  helper.settled === false &&
                  sameWindowsIdentity(helper.identity, target),
              )),
      );
      record.phase = "fault-intent";
      record.faultSha256 = armed.nativeEventSha256;
      record.faultIdentity = target;
      await wait(save());
      const fired = await wait(
        effects.fireFault(
          fault,
          structuredClone(admission),
          structuredClone(armed),
        ),
      );
      nativeEvent(fired, plan);
      requireWindows(
        fired.fault === fault &&
          fired.requestSha256 === admission.requestSha256 &&
          fired.faultSha256 === record.faultSha256 &&
          sameWindowsIdentity(fired.identity, target) &&
          !sameWindowsIdentity(systemIdentity(fired.verifier), target) &&
          fired.heldIdentityVerified === true &&
          fired.signaled === true &&
          hash(fired.nativeEventSha256),
      );
    }
    record.preserved = await wait(
      effects.snapshot(structuredClone(plan.value), structuredClone(admission)),
    );
    assertWindowsPolicySnapshot(record.preserved, plan.value);
    const filters = (snapshot) =>
      snapshot.wfp.filters.map((entry) => [entry.id, entry.descriptor]);
    const custody = windowsPolicyCustodyDigest(prepared.installation.effective);
    requireWindows(
      JSON.stringify(filters(record.preserved)) ===
        JSON.stringify(filters(prepared.installation.effective)) &&
        windowsPolicyCustodyDigest(record.preserved) === custody,
    );
    record.phase = "retirement-intent";
    await wait(save());
    record.retirement = await wait(effects.retire(structuredClone(admission)));
    assertWindowsRetirement(
      record.retirement,
      request,
      admission.requestSha256,
      plan.value.accountSid,
      admission.setup.job.heldObjectSha256,
    );
    assertWindowsPolicyHelpersRetired(record.retirement, admission);
    requireWindows(
      record.observation.members.every((member) =>
        record.retirement.members.some((identity) =>
          sameWindowsIdentity(member.identity, identity),
        ),
      ),
    );
    record.afterRetirement = await wait(
      effects.snapshot(structuredClone(plan.value), structuredClone(admission)),
    );
    assertWindowsPolicySnapshot(record.afterRetirement, plan.value);
    requireWindows(
      JSON.stringify(filters(record.afterRetirement)) ===
        JSON.stringify(filters(prepared.installation.effective)) &&
        windowsPolicyCustodyDigest(record.afterRetirement) === custody,
    );
    record.status = "OBSERVED";
    record.phase = "retired";
    await wait(save());
  } catch {
    record.status = "FAILED";
    record.phase = "excluded";
    await save();
    // Recovery remains a separate protected operation; failure never removes
    // filters, closes foreign handles or declares the account reusable.
  } finally {
    cancel(timer);
  }
  return record;
}
