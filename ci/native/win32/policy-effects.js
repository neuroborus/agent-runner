import { performance } from "node:perf_hooks";
import {
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsArguments,
  normalizeWindowsLaunch,
  sameWindowsIdentity,
  systemIdentity,
  windowsLaunchDigest,
} from "./protocol.js";
import { buildWindowsPolicy, assertWindowsPolicyToken } from "./policy.js";
import { assertWindowsRetirement, assessWindowsDomain } from "./recovery.js";
import {
  isWindows2025Image,
  normalizeNativePolicyBinding,
  assertNativePolicyParameters,
  verifyNativePolicy,
} from "../index.js";

export function windowsEffectiveRights(grant) {
  return {
    read: [
      "read",
      "read-tree",
      "edit",
      "workspace",
      "private-tree",
      "execute",
    ].includes(grant),
    write: grant === "edit",
    createFile: ["workspace", "private-tree"].includes(grant),
    createDirectory: ["workspace", "private-tree"].includes(grant),
    traverse: ["traverse", "read-tree", "workspace", "private-tree"].includes(
      grant,
    ),
    execute: grant === "execute",
    delete: grant === "edit",
    deleteChild: false,
    writeDacl: false,
    writeOwner: false,
  };
}

/** Stable custody identities from validated native snapshots. Fresh observation
 * digests may differ between reads without changing the reserved objects. */
export function windowsPolicyCustodyDigest(snapshot) {
  return digest(
    JSON.stringify({
      objects: snapshot.objects.map((entry) => [
        entry.descriptor,
        entry.descriptor.name === "registry"
          ? entry.registryIdentitySha256
          : [entry.volumeSerial, entry.fileId],
        entry.daclSha256,
      ]),
      endpoints: snapshot.endpoints.map((entry) => [
        entry.endpoint,
        entry.client?.reservationIdentitySha256 ?? null,
        entry.server.reservationIdentitySha256,
      ]),
    }),
  );
}

/** Settlement must include every helper in the protected admission receipt. */
export function assertWindowsPolicyHelpersRetired(retirement, admission) {
  const expected = dense(admission.helpers, 16).map((entry) =>
      systemIdentity(entry.identity),
    ),
    retired = dense(retirement.helpers, 32).map((entry) =>
      systemIdentity(entry.identity),
    );
  requireWindows(
    expected.length > 0 &&
      expected.every((identity) =>
        retired.some((entry) => sameWindowsIdentity(entry, identity)),
      ),
  );
}

/** Independent native handle, AccessCheck/MIC and effective BFE reads, including
 * the complete competing sublayer/flow view. Producer flags alone are invalid. */
export function assertWindowsPolicySnapshot(
  value,
  input,
  { installed = true } = {},
) {
  const plan = buildWindowsPolicy(input),
    { request } = plan.value;
  requireWindows(
    value?.independent === true &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      value.reviewSha256 === plan.value.reviewSha256 &&
      hash(value.nativeEventSha256) &&
      hash(value.reservationSha256) &&
      value.exclusiveWriter === true &&
      value.admissionsClosed === true,
  );
  const verifier = systemIdentity(value.verifier);
  assertWindowsPolicyToken(value.token, plan.value);
  requireWindows(
    value.inheritedAccessVerified === true &&
      value.mandatoryLabelsVerified === true &&
      value.hostObjectAccessReviewed === true &&
      value.noForeignHandles === true &&
      value.noDelegation === true &&
      value.noUnreviewedLoaderExceptions === true &&
      value.accountReservationVerified === true &&
      value.ancestorTraversalVerified === true &&
      value.disposableStorageVerified === plan.value.disposable &&
      value.baselineInventoryVerified === true &&
      value.inheritedOwnerRightsProtected === true &&
      value.creationDaclProtectionVerified === true &&
      value.registryParentProtected === true,
  );
  if (request.execution)
    requireWindows(
      value.privateTreeChildrenVerified === true &&
        value.separateStdioVerified === true &&
        value.brokerSystemPrincipalVerified === true,
    );
  const objects = dense(value.objects, 64);
  requireWindows(objects.length === plan.manifest.objects.length);
  const identities = new Set();
  objects.forEach((object, index) => {
    const expected = plan.manifest.objects[index];
    requireWindows(
      JSON.stringify(object.descriptor) === JSON.stringify(expected) &&
        hash(object.daclSha256) &&
        object.ownerSid === "S-1-5-18" &&
        object.protectedDacl === true &&
        object.noReparse === true &&
        object.exclusiveParents === true &&
        object.identityVerified === true &&
        object.accessCheckNative === true &&
        hash(object.nativeEventSha256) &&
        object.unexpectedAces === 0 &&
        object.foreignWritableHandles === 0 &&
        JSON.stringify(object.rights) ===
          JSON.stringify(windowsEffectiveRights(expected.grant)),
    );
    if (expected.name === "registry")
      requireWindows(hash(object.registryIdentitySha256));
    else {
      requireWindows(
        typeof object.volumeSerial === "string" &&
          /^[a-f0-9]{16}$/u.test(object.volumeSerial) &&
          typeof object.fileId === "string" &&
          /^[a-f0-9]{32}$/u.test(object.fileId) &&
          object.links === 1 &&
          (!expected.sha256 || object.sha256 === expected.sha256),
      );
      const identity = object.volumeSerial + ":" + object.fileId;
      requireWindows(!identities.has(identity));
      identities.add(identity);
    }
  });
  const wfp = value.wfp;
  requireWindows(
    wfp &&
      wfp.bfeRunning === true &&
      wfp.providerKey === plan.manifest.providerKey &&
      wfp.sublayerKey === plan.manifest.sublayerKey &&
      wfp.sublayerWeight === plan.manifest.sublayerWeight &&
      wfp.ownerSid === "S-1-5-18" &&
      wfp.protectedDacl === true &&
      wfp.systemOnlyDacl === true &&
      wfp.persistent === true &&
      wfp.dynamicSession === false &&
      wfp.transactionCommitted === true &&
      wfp.tokenConditionSha256 === plan.value.reviewSha256 &&
      wfp.localSocketPrincipal === true &&
      wfp.restrictedTokenMatchVerified === true &&
      wfp.unknownIdentityDenied === true &&
      wfp.connectAndReceiveBothDirections === true &&
      wfp.loopbackAleVerified === true &&
      wfp.udpReturnAleVerified === true &&
      wfp.globalPrecedenceVerified === true &&
      wfp.noConflictingHardPermit === true &&
      wfp.noLoopbackExemption === true &&
      wfp.noUnfilteredRoute === true &&
      wfp.noPreexistingFlows === true &&
      wfp.noForeignCallout === true &&
      hash(wfp.nativeEventSha256) &&
      hash(wfp.globalConfigurationSha256),
  );
  const filters = dense(wfp.filters, 64);
  requireWindows(
    filters.length === (installed ? plan.manifest.filters.length : 0),
  );
  const ids = new Set();
  filters.forEach((filter, index) => {
    requireWindows(
      JSON.stringify(filter.descriptor) ===
        JSON.stringify(plan.manifest.filters[index]) &&
        typeof filter.id === "string" &&
        /^[1-9][0-9]{0,19}$/u.test(filter.id) &&
        BigInt(filter.id) <= 0xffffffffffffffffn &&
        hash(filter.nativeEventSha256) &&
        filter.providerKey === wfp.providerKey &&
        filter.sublayerKey === wfp.sublayerKey &&
        filter.userConditionIncludesRestrictingSid ===
          (filter.descriptor.principal === plan.value.accountSid) &&
        !ids.has(filter.id),
    );
    ids.add(filter.id);
  });
  const endpoints = dense(value.endpoints, 4);
  requireWindows(endpoints.length === plan.value.endpoints.length);
  endpoints.forEach((entry, index) => {
    requireWindows(
      JSON.stringify(entry.endpoint) ===
        JSON.stringify(plan.value.endpoints[index]) &&
        entry.reserved === true &&
        entry.exclusive === true &&
        entry.noWildcard === true &&
        entry.noPortReuse === true &&
        entry.ipv6Only === (entry.endpoint.family === "v6") &&
        hash(entry.nativeEventSha256) &&
        entry.systemCustodied === true &&
        entry.transferOnlyToVerifiedPrincipal === true,
    );
    if (request.execution) {
      requireWindows(
        entry.server?.userSid === "S-1-5-18" &&
          entry.server.heldReservationVerified === true &&
          hash(entry.server.reservationIdentitySha256) &&
          entry.server.processIdentityVerified === true &&
          entry.clientEphemeralOnly === true &&
          entry.receivingPrincipalVerified === true,
      );
      return;
    }
    for (const side of ["client", "server"])
      requireWindows(
        entry[side]?.userSid === plan.value.accountSid &&
          JSON.stringify(entry[side].restrictedSids) ===
            JSON.stringify([request.restrictingSid]) &&
          entry[side].heldReservationVerified === true &&
          hash(entry[side].reservationIdentitySha256),
      );
  });
  return verifier;
}

function baseline(value, plan) {
  requireWindows(
    value.independent === true &&
      value.admissionsClosed === true &&
      value.exclusiveWriter === true &&
      value.noExistingOwnedPolicy === true &&
      value.accountReservationVerified === true &&
      value.registryAbsent === true &&
      value.baselineInventoryVerified === true &&
      value.candidateSha === plan.value.request.candidateSha &&
      value.nonce === plan.value.request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      hash(value.nativeEventSha256),
  );
  systemIdentity(value.verifier);
  const expected = plan.manifest.objects.filter(
      (entry) => entry.name !== "registry",
    ),
    objects = dense(value.objects, 44);
  requireWindows(objects.length === expected.length);
  const identities = new Set();
  objects.forEach((object, index) => {
    requireWindows(
      object.path === expected[index].path &&
        object.ownerSid === "S-1-5-18" &&
        object.protectedDacl === true &&
        object.systemOnlyDacl === true &&
        object.exclusiveParents === true &&
        object.noReparse === true &&
        object.links === 1 &&
        object.identityVerified === true &&
        object.foreignWritableHandles === 0 &&
        hash(object.nativeEventSha256) &&
        hash(object.daclSha256) &&
        typeof object.volumeSerial === "string" &&
        /^[a-f0-9]{16}$/u.test(object.volumeSerial) &&
        typeof object.fileId === "string" &&
        /^[a-f0-9]{32}$/u.test(object.fileId) &&
        (!expected[index].sha256 || object.sha256 === expected[index].sha256),
    );
    const identity = object.volumeSerial + ":" + object.fileId;
    requireWindows(!identities.has(identity));
    identities.add(identity);
  });
}

export function assertWindowsPolicyInstallation(value, input) {
  const plan = buildWindowsPolicy(input),
    { request } = plan.value;
  requireWindows(
    request.policy.sha256 === plan.policySha256 &&
      request.bindings.policy === plan.compositionSha256 &&
      value?.status === "INSTALLED" &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      value.policySha256 === plan.policySha256 &&
      value.reservation === "RETAINED" &&
      value.helpersSettled === true &&
      hash(value.receiptSha256),
  );
  assertWindowsPolicySnapshot(value.effective, plan.value);
  return value;
}

/** External CI supplies reviewed native bridges. Persisted intents precede all
 * writes; timeout leaves persistent BFE filters and every reservation intact. */
export async function configureWindowsPolicy(
  input,
  approvedSha256,
  effects,
  {
    operation = "install",
    previous,
    retirement,
    admission,
    onHelper,
    provisioning,
    argumentsList = [],
    platform = process.platform,
    architecture = process.arch,
    env = process.env,
    build = "",
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const plan = buildWindowsPolicy(input),
    { request } = plan.value;
  const policyBinding =
    typeof approvedSha256 === "object" && approvedSha256 !== null
      ? normalizeNativePolicyBinding(approvedSha256)
      : null;
  if (policyBinding) {
    argumentsList = normalizeWindowsArguments(argumentsList);
    assertNativePolicyParameters(
      policyBinding,
      provisioning,
      plan.value,
      argumentsList,
    );
    provisioning = structuredClone(provisioning);
    approvedSha256 = policyBinding.approval.manifestSha256;
  }
  if (request.schemaVersion >= 3) requireWindows(policyBinding !== null);
  requireWindows(
    ["install", "remove"].includes(operation) &&
      platform === "win32" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      isWindows2025Image({
        build,
        imageOS: env.ImageOS,
        imageVersion: env.ImageVersion,
      }) &&
      typeof effects?.persist === "function",
  );
  previous = structuredClone(previous);
  retirement = structuredClone(retirement);
  admission = structuredClone(admission);
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    compositionSha256: plan.compositionSha256,
    policySha256: plan.policySha256,
    operation,
    status: "BLOCKED",
    phase: "review",
    reservation: "RETAINED",
    helpers: [],
    helpersSettled: false,
    missingInputs: [],
    ...(policyBinding ? { templateSha256: approvedSha256 } : {}),
  };
  for (const key of [
    "review",
    "snapshot",
    "mutate",
    "verifySettlement",
    "verifyReceipt",
  ])
    if (typeof effects?.[key] !== "function")
      record.missingInputs.push("windows-policy-" + key);
  if (operation === "remove" && typeof effects.verifyRetirement !== "function")
    record.missingInputs.push("windows-policy-verifyRetirement");
  if (
    policyBinding &&
    operation === "install" &&
    typeof effects.readPolicy !== "function"
  )
    record.missingInputs.push("windows-policy-readPolicy");
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
    rejectDeadline(new Error("Windows policy deadline"));
  }, 30000);
  const bounded = () =>
    requireWindows(
      !expired &&
        Number.isFinite(now() - start) &&
        now() - start >= 0 &&
        now() - start < 30000,
    );
  const wait = async (promise) => {
    const result = await Promise.race([promise, deadline]);
    bounded();
    return structuredClone(result);
  };
  try {
    requireWindows(
      (policyBinding !== null || approvedSha256 === plan.compositionSha256) &&
        request.bindings.policy === plan.compositionSha256 &&
        request.policy.sha256 === plan.policySha256,
    );
    const review = await wait(
      effects.review(
        structuredClone(plan),
        approvedSha256,
        structuredClone(policyBinding),
      ),
    );
    if (review.missingInputs?.length) {
      record.missingInputs = dense(review.missingInputs, 64);
      requireWindows(
        record.missingInputs.every(
          (entry) =>
            typeof entry === "string" && /^[a-z0-9.-]{1,128}$/u.test(entry),
        ),
      );
      await wait(save());
      return record;
    }
    requireWindows(
      review.approvedSha256 === approvedSha256 &&
        review.localSystemSession0 === true &&
        hash(review.helperImageSha256) &&
        hash(review.helperSourceSha256) &&
        review.sdkExportsVerified === true &&
        review.loaderClosureVerified === true &&
        review.completeCompositionReviewed === true,
    );
    let retirementVerifier;
    if (operation === "remove") {
      assertWindowsPolicyInstallation(previous, plan.value);
      requireWindows(
        ["RUNNING", "ADMITTED", "FAIL"].includes(admission.status) &&
          admission.admission === "possible" &&
          admission.reservation === "RETAINED" &&
          admission.candidateSha === request.candidateSha &&
          admission.nonce === request.nonce &&
          admission.accountSid === plan.value.accountSid &&
          JSON.stringify(normalizeWindowsLaunch(admission.request)) ===
            JSON.stringify(request) &&
          admission.requestSha256 ===
            windowsLaunchDigest(request, admission.arguments) &&
          admission.policyReceiptSha256 === previous.receiptSha256 &&
          hash(admission.setup?.job?.heldObjectSha256),
      );
      retirementVerifier = assertWindowsRetirement(
        retirement,
        request,
        admission.requestSha256,
        plan.value.accountSid,
        admission.setup.job.heldObjectSha256,
      );
      assertWindowsPolicyHelpersRetired(retirement, admission);
      const fresh = await wait(
        effects.verifyRetirement(
          structuredClone(retirement),
          structuredClone(admission),
        ),
      );
      requireWindows(
        fresh.independent === true &&
          fresh.candidateSha === request.candidateSha &&
          fresh.nonce === request.nonce &&
          fresh.requestSha256 === admission.requestSha256 &&
          fresh.retirementSha256 ===
            digest(JSON.stringify(retirement) + "\n") &&
          fresh.admissionsClosed === true &&
          fresh.helpersSettled === true &&
          fresh.heldProcessesSignaled === true &&
          fresh.noForeignCreators === true &&
          fresh.noPrincipalFlows === true &&
          fresh.protectedReceiptVerified === true &&
          fresh.admissionReceiptVerified === true &&
          fresh.policyReceiptSha256 === previous.receiptSha256 &&
          hash(fresh.nativeEventSha256) &&
          !sameWindowsIdentity(
            systemIdentity(fresh.verifier),
            retirementVerifier,
          ),
      );
      requireWindows(
        typeof fresh.jobPresent === "boolean" &&
          fresh.domain?.candidateSha === request.candidateSha &&
          fresh.domain.nonce === request.nonce &&
          fresh.domain.jobObjectSha256 ===
            admission.setup.job.heldObjectSha256 &&
          fresh.domain.jobPresent === fresh.jobPresent &&
          assessWindowsDomain(
            fresh.domain,
            plan.value.accountSid,
            admission.setup.job.heldObjectSha256,
            fresh.jobPresent,
          ).every((entry) => entry.signaled),
      );
      record.retirementSha256 = fresh.retirementSha256;
    }
    record.phase = "before-write";
    await wait(save());
    bounded();
    const before = await wait(
      effects.snapshot(structuredClone(plan.value), operation),
    );
    if (operation === "remove") {
      assertWindowsPolicySnapshot(before, plan.value);
      const filters = (snapshot) =>
        snapshot.wfp.filters.map((entry) => [entry.id, entry.descriptor]);
      requireWindows(
        windowsPolicyCustodyDigest(before) ===
          windowsPolicyCustodyDigest(previous.effective) &&
          JSON.stringify(filters(before)) ===
            JSON.stringify(filters(previous.effective)),
      );
    } else baseline(before, plan);
    record.phase = operation + "-intent";
    record.beforeSha256 = before.nativeEventSha256;
    await wait(save());
    bounded();
    let helperAdmission = "open";
    const admitHelper = async (helper) => {
      try {
        bounded();
        requireWindows(
          helperAdmission === "open" &&
            record.helpers.length === 0 &&
            helper.imageSha256 === review.helperImageSha256 &&
            helper.sourceSha256 === review.helperSourceSha256,
        );
        const identity = systemIdentity(helper.identity);
        requireWindows(!sameWindowsIdentity(identity, before.verifier));
        helperAdmission = "pending";
        record.helpers.push({
          identity,
          imageSha256: helper.imageSha256,
          sourceSha256: helper.sourceSha256,
          settled: false,
        });
        await wait(save());
        bounded();
        requireWindows(helperAdmission === "pending");
        if (onHelper)
          await onHelper({
            ...structuredClone(helper),
            role: "wfp",
            settled: false,
          });
        bounded();
        requireWindows(helperAdmission === "pending");
        helperAdmission = "complete";
      } catch (error) {
        helperAdmission = "failed";
        throw error;
      }
    };
    try {
      await wait(
        effects.mutate(
          structuredClone(plan),
          operation,
          admitHelper,
          structuredClone(before),
        ),
      );
      requireWindows(helperAdmission === "complete");
    } finally {
      helperAdmission = "closed";
    }
    requireWindows(record.helpers.length === 1);
    const settled = await wait(
      effects.verifySettlement(structuredClone(record.helpers)),
    );
    requireWindows(
      settled.independent === true &&
        settled.signaled === true &&
        settled.exitCode === 0 &&
        settled.timedOut === false &&
        hash(settled.nativeEventSha256) &&
        sameWindowsIdentity(settled.helper, record.helpers[0].identity) &&
        !sameWindowsIdentity(systemIdentity(settled.verifier), settled.helper),
    );
    record.helpers[0].settled = true;
    record.helpersSettled = true;
    record.phase = "effective";
    await wait(save());
    bounded();
    record.effective = await wait(
      effects.snapshot(structuredClone(plan.value), "effective"),
    );
    const verifier = assertWindowsPolicySnapshot(record.effective, plan.value, {
      installed: operation === "install",
    });
    requireWindows(
      !record.helpers.some((helper) =>
        sameWindowsIdentity(helper.identity, verifier),
      ) &&
        (operation !== "remove" ||
          windowsPolicyCustodyDigest(record.effective) ===
            windowsPolicyCustodyDigest(before)),
    );
    for (const object of before.objects) {
      const path = object.path ?? object.descriptor.path;
      const after = record.effective.objects.find(
        (entry) => entry.descriptor.path === path,
      );
      requireWindows(
        after &&
          after.volumeSerial === object.volumeSerial &&
          after.fileId === object.fileId,
      );
      if (object.descriptor?.name === "registry")
        requireWindows(
          after.registryIdentitySha256 === object.registryIdentitySha256,
        );
    }
    if (policyBinding && operation === "install")
      record.policyReceipt = verifyNativePolicy(
        policyBinding.template,
        policyBinding.approval,
        provisioning,
        policyBinding.context,
        windowsLaunchDigest(request, argumentsList),
        await wait(
          effects.readPolicy(structuredClone(request), structuredClone(record)),
        ),
      );
    record.status = operation === "install" ? "INSTALLED" : "REMOVED";
    record.phase = "receipt";
    await wait(save());
    bounded();
    const receipt = await wait(effects.verifyReceipt(structuredClone(record)));
    requireWindows(
      receipt.independent === true &&
        receipt.immutable === true &&
        hash(receipt.sha256) &&
        !record.helpers.some((helper) =>
          sameWindowsIdentity(
            helper.identity,
            systemIdentity(receipt.verifier),
          ),
        ) &&
        receipt.contentSha256 === digest(JSON.stringify(record) + "\n"),
    );
    record.receiptSha256 = receipt.sha256;
    await wait(save());
  } catch {
    record.status = "FAILED";
    record.phase = "excluded";
    await save();
  } finally {
    cancel(timer);
  }
  return record;
}
